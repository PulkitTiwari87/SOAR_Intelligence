import { afterEach, describe, expect, it } from 'vitest';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { useLoad } from './ui';

const deferred = () => {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
};

describe('useLoad', () => {
  afterEach(cleanup);

  it('starts loading, then exposes the data', async () => {
    const { result } = renderHook(() => useLoad(async () => ({ n: 1 }), []));
    expect(result.current.loading).toBe(true);
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.data).toEqual({ n: 1 });
    expect(result.current.error).toBeNull();
  });

  it('exposes an error message instead of throwing', async () => {
    const { result } = renderHook(() => useLoad(async () => { throw new Error('boom'); }, []));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toBe('boom');
    expect(result.current.data).toBeNull();
  });

  it('ignores a slow response that was superseded by a newer request', async () => {
    const pending = { 1: deferred(), 2: deferred() };
    const { result, rerender } = renderHook(({ id }) => useLoad(() => pending[id].promise, [id]), { initialProps: { id: 1 } });
    rerender({ id: 2 });
    await act(async () => { pending[2].resolve('second'); });
    await waitFor(() => expect(result.current.data).toBe('second'));
    await act(async () => { pending[1].resolve('first (stale)'); });
    expect(result.current.data).toBe('second');
  });

  it('reload() fetches again', async () => {
    let calls = 0;
    const { result } = renderHook(() => useLoad(async () => ++calls, []));
    await waitFor(() => expect(result.current.data).toBe(1));
    act(() => result.current.reload());
    await waitFor(() => expect(result.current.data).toBe(2));
  });
});
