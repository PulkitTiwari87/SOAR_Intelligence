import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

vi.mock('./api', async (importOriginal) => ({
  ...(await importOriginal()),
  api: { get: vi.fn(), post: vi.fn() },
}));

import { api } from './api';
import { AuthProvider } from './auth';
import Login from './pages/Login';

const httpError = (status, detail) => Object.assign(new Error(`HTTP ${status}`), { response: { status, data: { detail } } });
const SESSION = { data: { user: { username: 'alice' }, permissions: ['view'] } };

async function fillAndSubmit(user, username = 'alice', password = 'wrong-password') {
  await user.type(screen.getByLabelText('Username'), username);
  await user.type(screen.getByLabelText('Password'), password);
  await user.click(screen.getByRole('button', { name: /sign in/i }));
}

function renderLogin() {
  render(<MemoryRouter><AuthProvider><Login /></AuthProvider></MemoryRouter>);
  return userEvent.setup();
}

describe('login form', () => {
  beforeEach(() => vi.resetAllMocks());
  afterEach(cleanup);

  it('keeps what the user typed and shows a safe message when credentials are wrong', async () => {
    api.get.mockRejectedValue(httpError(401, 'Not authenticated'));
    api.post.mockRejectedValue(httpError(401, 'Invalid credentials'));
    const user = renderLogin();
    await fillAndSubmit(user);
    expect((await screen.findByRole('alert')).textContent).toBe('Invalid credentials');
    expect(screen.getByLabelText('Username').value).toBe('alice');
    expect(screen.getByRole('button', { name: /sign in/i }).disabled).toBe(false);
  });

  it('shows the throttling message and stays usable when rate limited', async () => {
    api.get.mockRejectedValue(httpError(401, 'Not authenticated'));
    api.post.mockRejectedValue(httpError(429, 'Too many failed attempts. Try again later.'));
    const user = renderLogin();
    await fillAndSubmit(user);
    expect((await screen.findByRole('alert')).textContent).toMatch(/too many failed attempts/i);
    expect(screen.getByLabelText('Username').value).toBe('alice');
  });

  it('disables the button while signing in so the form cannot be submitted twice', async () => {
    api.get.mockRejectedValue(httpError(401, 'Not authenticated'));
    api.post.mockReturnValue(new Promise(() => {})); // never settles: request stays in flight
    const user = renderLogin();
    await fillAndSubmit(user);
    const button = await screen.findByRole('button', { name: /signing in/i });
    expect(button.disabled).toBe(true);
    await user.click(button);
    expect(api.post).toHaveBeenCalledTimes(1);
    expect(screen.getByLabelText('Username').value).toBe('alice');
  });

  it('trims the username and loads the session after a successful login', async () => {
    api.get.mockRejectedValueOnce(httpError(401, 'Not authenticated')).mockResolvedValue(SESSION);
    api.post.mockResolvedValue({ data: {} });
    const user = renderLogin();
    await fillAndSubmit(user, '  alice  ', 'correct-horse-battery');
    await vi.waitFor(() => expect(api.get).toHaveBeenCalledTimes(2));
    expect(api.post).toHaveBeenCalledWith('/auth/login', { username: 'alice', password: 'correct-horse-battery' });
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('explains it when the password is accepted but no session is established', async () => {
    api.get.mockRejectedValue(httpError(401, 'Not authenticated')); // cookie dropped: /auth/me stays anonymous
    api.post.mockResolvedValue({ data: {} });
    const user = renderLogin();
    await fillAndSubmit(user, 'alice', 'correct-horse-battery');
    expect((await screen.findByRole('alert')).textContent).toMatch(/did not keep the session/i);
    expect(screen.getByRole('button', { name: /sign in/i }).disabled).toBe(false);
  });
});
