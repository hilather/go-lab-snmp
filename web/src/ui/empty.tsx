import type { ReactNode } from "react";

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <p className="muted empty-state" role="status">
      {children}
    </p>
  );
}
