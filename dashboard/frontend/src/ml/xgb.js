// Minimal XGBoost inference for the exported native-JSON model (binary:logistic), plus exact
// path-dependent TreeSHAP (Lundberg et al.), matching xgboost's `pred_contribs`. Used by the public ML
// demo so the browser runs the real trained trees rather than a re-implementation of their outputs.
// Parity with the Python backend is asserted in xgb.test.js against values exported from the backend.

const f32 = Math.fround;

export function loadModel(json) {
  const p = json.learner.learner_model_param;
  const baseScore = Number(String(p.base_score).replace(/[[\]]/g, ''));
  const trees = json.learner.gradient_booster.model.trees.map((t) => ({
    left: t.left_children, right: t.right_children, feat: t.split_indices,
    cond: t.split_conditions.map(f32), value: t.split_conditions, // leaves store their value here
    dl: t.default_left, cover: t.sum_hessian,
  }));
  const baseMargin = Math.log(baseScore / (1 - baseScore));
  const bias = baseMargin + trees.reduce((s, t) => s + expected(t, 0), 0);
  return { trees, baseMargin, bias, nFeatures: Number(p.num_feature) };
}

function expected(t, j) {
  if (t.left[j] === -1) return t.value[j];
  const l = t.left[j], r = t.right[j];
  return (expected(t, l) * t.cover[l] + expected(t, r) * t.cover[r]) / t.cover[j];
}

const child = (t, j, x) => {
  const v = x[t.feat[j]];
  if (v === undefined || Number.isNaN(v)) return t.dl[j] ? t.left[j] : t.right[j];
  return f32(v) < t.cond[j] ? t.left[j] : t.right[j];
};

export function predictMargin(model, x) {
  let m = model.baseMargin;
  for (const t of model.trees) {
    let j = 0;
    while (t.left[j] !== -1) j = child(t, j, x);
    m += t.value[j];
  }
  return m;
}

export const predictProba = (model, x) => 1 / (1 + Math.exp(-predictMargin(model, x)));

// ── TreeSHAP ──
function extend(path, pz, po, pi) {
  const l = path.length;
  path.push({ d: pi, z: pz, o: po, w: l === 0 ? 1 : 0 });
  for (let i = l - 1; i >= 0; i--) {
    path[i + 1].w += (po * path[i].w * (i + 1)) / (l + 1);
    path[i].w = (pz * path[i].w * (l - i)) / (l + 1);
  }
}

function unwind(path, i) {
  const l = path.length - 1, { o, z } = path[i];
  let n = path[l].w;
  for (let j = l - 1; j >= 0; j--) {
    if (o !== 0) {
      const t = path[j].w;
      path[j].w = (n * (l + 1)) / ((j + 1) * o);
      n = t - (path[j].w * z * (l - j)) / (l + 1);
    } else {
      path[j].w = (path[j].w * (l + 1)) / (z * (l - j));
    }
  }
  for (let j = i; j < l; j++) Object.assign(path[j], { d: path[j + 1].d, z: path[j + 1].z, o: path[j + 1].o });
  path.pop();
}

function unwoundSum(path, i) {
  const l = path.length - 1, { o, z } = path[i];
  let n = path[l].w, total = 0;
  for (let j = l - 1; j >= 0; j--) {
    if (o !== 0) {
      const t = (n * (l + 1)) / ((j + 1) * o);
      total += t;
      n = path[j].w - (t * z * (l - j)) / (l + 1);
    } else {
      total += path[j].w / (z * ((l - j) / (l + 1)));
    }
  }
  return total;
}

/** Per-feature log-odds contributions; sum(shap) + model.bias === predictMargin(). */
export function shap(model, x) {
  const phi = new Array(model.nFeatures).fill(0);
  for (const t of model.trees) {
    const rec = (j, parent, pz, po, pi) => {
      const path = parent.map((p) => ({ ...p }));
      extend(path, pz, po, pi);
      if (t.left[j] === -1) {
        for (let i = 1; i < path.length; i++) phi[path[i].d] += unwoundSum(path, i) * (path[i].o - path[i].z) * t.value[j];
        return;
      }
      const hot = child(t, j, x), cold = hot === t.left[j] ? t.right[j] : t.left[j], d = t.feat[j];
      let iz = 1, io = 1;
      const k = path.findIndex((p, idx) => idx > 0 && p.d === d);
      if (k > 0) { iz = path[k].z; io = path[k].o; unwind(path, k); }
      rec(hot, path, (iz * t.cover[hot]) / t.cover[j], io, d);
      rec(cold, path, (iz * t.cover[cold]) / t.cover[j], 0, d);
    };
    rec(0, [], 1, 1, -1);
  }
  return phi;
}
