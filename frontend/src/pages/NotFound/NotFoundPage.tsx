import { Link } from "react-router-dom";
import { Compass, Home } from "lucide-react";

export default function NotFoundPage() {
  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <div className="rounded-2xl border border-slate-800 bg-slate-900 p-10 text-center">
        <Compass className="mx-auto mb-6 text-cyan-400" size={48} />

        <h1 className="text-4xl font-bold text-white">404</h1>

        <p className="mt-3 text-slate-400">
          The page you are looking for does not exist.
        </p>

        <Link
          to="/dashboard"
          className="mt-8 inline-flex items-center gap-2 rounded-lg bg-cyan-500 px-6 py-3 font-semibold text-black transition hover:bg-cyan-400"
        >
          <Home size={18} />
          Back to Dashboard
        </Link>
      </div>
    </div>
  );
}
