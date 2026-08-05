import type { ReactNode } from "react";

import Sidebar from "../navigation/Sidebar";
import Header from "../navigation/Header";

interface Props {
  children: ReactNode;
}

export default function AppLayout({ children }: Props) {
  return (
    <div className="h-screen bg-slate-950 flex">

      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">

        <Header />

        <main className="flex-1 overflow-auto bg-slate-950 p-8">

          {children}

        </main>

      </div>

    </div>
  );
}