import { useEffect, useRef } from 'react';

export interface SSECallbacks {
    onProgress?: (data: { percent: number; phase: string }) => void;
    onPhaseChange?: (data: { phase: string }) => void;
    onFinding?: (data: Record<string, unknown>) => void;
    onCompleted?: () => void;
    onError?: () => void;
}

/**
 * Subscribes to a server-sent events stream for real-time scan updates.
 * Automatically cleans up the EventSource on unmount or when `url` changes.
 * Pass `null` as `url` to disable (e.g. when the scan is already finished).
 */
export function useSSE(url: string | null, callbacks: SSECallbacks): void {
    const cbRef = useRef(callbacks);
    cbRef.current = callbacks; // always up-to-date without re-subscribing

    useEffect(() => {
        if (!url) return;

        const es = new EventSource(url);

        const parse = (raw: string): Record<string, unknown> => {
            try { return JSON.parse(raw); } catch { return {}; }
        };

        es.addEventListener('progress', (e: MessageEvent) => {
            cbRef.current.onProgress?.(parse(e.data) as { percent: number; phase: string });
        });

        es.addEventListener('phase_change', (e: MessageEvent) => {
            cbRef.current.onPhaseChange?.(parse(e.data) as { phase: string });
        });

        es.addEventListener('finding', (e: MessageEvent) => {
            cbRef.current.onFinding?.(parse(e.data));
        });

        es.addEventListener('completed', () => {
            cbRef.current.onCompleted?.();
            es.close();
        });

        es.addEventListener('error', () => {
            cbRef.current.onError?.();
            es.close();
        });

        // Fallback: native onerror (connection-level failure)
        es.onerror = () => {
            cbRef.current.onError?.();
            es.close();
        };

        return () => {
            es.close();
        };
    }, [url]);
}
