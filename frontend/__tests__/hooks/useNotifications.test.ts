import { renderHook, act } from '@testing-library/react';
import { useNotifications } from '@/hooks/useNotifications';

// Don't use the actual module — test the real implementation
describe('useNotifications', () => {
  it('returns initial demo notifications', () => {
    const { result } = renderHook(() => useNotifications());
    expect(result.current.notifications.length).toBeGreaterThan(0);
  });

  it('has correct unreadCount from demo data', () => {
    const { result } = renderHook(() => useNotifications());
    const unread = result.current.notifications.filter((n) => !n.read).length;
    expect(result.current.unreadCount).toBe(unread);
  });

  it('markRead sets notification read=true', () => {
    const { result } = renderHook(() => useNotifications());
    const unreadId = result.current.notifications.find((n) => !n.read)?.id;
    if (!unreadId) return;
    act(() => result.current.markRead(unreadId));
    const notif = result.current.notifications.find((n) => n.id === unreadId);
    expect(notif?.read).toBe(true);
  });

  it('markAllRead sets all notifications read', () => {
    const { result } = renderHook(() => useNotifications());
    act(() => result.current.markAllRead());
    expect(result.current.unreadCount).toBe(0);
    result.current.notifications.forEach((n) => expect(n.read).toBe(true));
  });

  it('dismiss removes notification by id', () => {
    const { result } = renderHook(() => useNotifications());
    const id = result.current.notifications[0].id;
    const countBefore = result.current.notifications.length;
    act(() => result.current.dismiss(id));
    expect(result.current.notifications.length).toBe(countBefore - 1);
    expect(result.current.notifications.find((n) => n.id === id)).toBeUndefined();
  });

  it('clearAll empties notifications', () => {
    const { result } = renderHook(() => useNotifications());
    act(() => result.current.clearAll());
    expect(result.current.notifications.length).toBe(0);
    expect(result.current.unreadCount).toBe(0);
  });

  it('pushLocal adds a notification', () => {
    const { result } = renderHook(() => useNotifications());
    const before = result.current.notifications.length;
    act(() => result.current.pushLocal('system', 'Test', 'test body', 'info'));
    expect(result.current.notifications.length).toBe(before + 1);
    const added = result.current.notifications[0];
    expect(added.title).toBe('Test');
    expect(added.severity).toBe('info');
    expect(added.read).toBe(false);
  });

  it('pushLocal marks new notification as unread', () => {
    const { result } = renderHook(() => useNotifications());
    act(() => result.current.markAllRead());
    act(() => result.current.pushLocal('system', 'New', 'body', 'critical'));
    expect(result.current.unreadCount).toBe(1);
  });

  it('unreadCritical counts only critical unread', () => {
    const { result } = renderHook(() => useNotifications());
    act(() => result.current.clearAll());
    act(() => result.current.pushLocal('finding_critical', 'C', 'c', 'critical'));
    act(() => result.current.pushLocal('scan_completed', 'I', 'i', 'info'));
    expect(result.current.unreadCritical).toBe(1);
  });

  it('respects maxNotifications limit', () => {
    const { result } = renderHook(() => useNotifications({ maxNotifications: 3 }));
    act(() => result.current.clearAll());
    for (let i = 0; i < 5; i++) {
      act(() => result.current.pushLocal('system', `N${i}`, 'body', 'info'));
    }
    expect(result.current.notifications.length).toBe(3);
  });

  it('wsStatus defaults to disconnected when no wsUrl', () => {
    const { result } = renderHook(() => useNotifications());
    expect(result.current.wsStatus).toBe('disconnected');
  });

  it('onNotification registers listener and removes on unsubscribe', () => {
    const { result } = renderHook(() => useNotifications());
    const handler = jest.fn();
    let unsub: () => void;
    act(() => { unsub = result.current.onNotification(handler); });
    act(() => result.current.pushLocal('system', 'T', 'b', 'info'));
    expect(handler).toHaveBeenCalledTimes(1);
    act(() => unsub());
    act(() => result.current.pushLocal('system', 'T2', 'b2', 'info'));
    expect(handler).toHaveBeenCalledTimes(1); // not called again
  });
});
