import { type ReactNode } from "react";
import { X } from "lucide-react";

interface SlideOverProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
}

export function SlideOver({ open, onClose, title, children }: SlideOverProps) {
  if (!open) return null;

  return (
    <div
      className="fixed right-0 top-0 h-screen w-[440px] bg-canvas border-l border-hairline z-50 flex flex-col"
      style={{
        transform: open ? "translateX(0)" : "translateX(100%)",
        transition: "transform 200ms ease-in-out",
      }}
    >
            <div
 className="flex items-center justify-between h-14 px-lg border-b border-hairline shrink-0">
        <span className="text-sm font-semibold text-ink">{title}</span>
        <button
          onClick={onClose}
          className="text-mute hover:text-ink transition-colors cursor-pointer"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      <div className="flex-1 overflow-auto p-lg">{children}</div>
    </div>
  );
}
