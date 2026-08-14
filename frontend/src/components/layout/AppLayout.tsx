import { useState } from "react";
import type { ReactNode } from "react";

import Sidebar from "../navigation/Sidebar";
import Header from "../navigation/Header";

interface Props {
  children: ReactNode;
}

export default function AppLayout({ children }: Props) {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="h-screen bg-slate-950 flex">

      <Sidebar
        mobileOpen={mobileOpen}
        onClose={() => setMobileOpen(false)}
      />

      <div className="flex-1 flex flex-col overflow-hidden">

        <Header onMenuClick={() => setMobileOpen(true)} />

        <main className="flex-1 overflow-auto bg-slate-950 p-8">

          {children}

        </main>

      </div>

    </div>
  );
}