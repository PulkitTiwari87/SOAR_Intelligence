const { execFile } = require('child_process');
const path = require('path');

const SOAR_ROOT = process.env.SOAR_PROJECT_ROOT || path.resolve(__dirname, '../../../');

/**
 * Run a Python script and return parsed JSON output.
 * @param {string} scriptPath - Relative path from SOAR project root
 * @param {string[]} args - Command-line arguments
 * @returns {Promise<object>} Parsed JSON from stdout
 */
function runPython(scriptPath, args = []) {
  return new Promise((resolve, reject) => {
    const fullPath = path.join(SOAR_ROOT, scriptPath);

    execFile('python3', [fullPath, ...args], {
      cwd: SOAR_ROOT,
      timeout: 30000,
      maxBuffer: 1024 * 1024 * 5, // 5MB
      env: { ...process.env, PYTHONPATH: SOAR_ROOT },
    }, (error, stdout, stderr) => {
      if (error) {
        console.error(`[PythonBridge] Error running ${scriptPath}:`, error.message);
        if (stderr) console.error(`[PythonBridge] stderr:`, stderr);
        return reject(new Error(`Python script failed: ${error.message}`));
      }

      try {
        // Extract the last valid JSON from stdout (scripts may print debug info before JSON)
        const lines = stdout.trim().split('\n');
        let jsonStr = '';

        // Try to find JSON object/array in output (search from end)
        for (let i = lines.length - 1; i >= 0; i--) {
          const trimmed = lines[i].trim();
          if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
            // Collect from this line to end
            jsonStr = lines.slice(i).join('\n');
            break;
          }
        }

        if (!jsonStr) {
          // Fallback: try entire stdout
          jsonStr = stdout.trim();
        }

        const result = JSON.parse(jsonStr);
        resolve(result);
      } catch (parseErr) {
        // Return raw stdout if not JSON
        resolve({ raw: stdout.trim(), stderr: stderr.trim() });
      }
    });
  });
}

/**
 * Run a Python expression via -c flag
 */
function runPythonExpr(code) {
  return new Promise((resolve, reject) => {
    execFile('python3', ['-c', code], {
      cwd: SOAR_ROOT,
      timeout: 15000,
      env: { ...process.env, PYTHONPATH: SOAR_ROOT },
    }, (error, stdout, stderr) => {
      if (error) return reject(new Error(error.message));
      try {
        resolve(JSON.parse(stdout.trim()));
      } catch {
        resolve({ raw: stdout.trim() });
      }
    });
  });
}

module.exports = { runPython, runPythonExpr, SOAR_ROOT };
