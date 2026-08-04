import { useLocation } from "react-router-dom";
import { startInvestigation } from "../../services/investigationService";

export default function InvestigationPage() {

  const location = useLocation();
  console.log(location);

  const investigation = location.state;

  async function handleStart() {

    if (!investigation) return;

    const result = await startInvestigation(
      investigation.investigation_id,
      investigation.stored_path,
    );

    alert(result.message);

  }

  return (

    <div className="space-y-8">

      <h1 className="text-4xl font-bold text-white">

        Investigation

      </h1>

      {investigation ? (

        <div className="rounded-xl border border-slate-700 bg-slate-900 p-6">

          <p className="text-slate-300">

            Investigation ID

          </p>

          <p className="font-mono text-cyan-400">

            {investigation.investigation_id}

          </p>

          <button

            onClick={handleStart}

            className="mt-6 rounded-lg bg-cyan-500 px-6 py-3 font-semibold text-black"

          >

            Start Investigation

          </button>

        </div>

      ) : (

        <p className="text-slate-400">

          No uploaded memory dump found.

        </p>

      )}

    </div>

  );

}