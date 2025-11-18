import { useAuth } from "../contexts/AuthContext";
import { UserIcon } from "@heroicons/react/24/solid";

const ProfilePage = () => {
  const { userEmail, userPlan } = useAuth();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-slate-900">Perfil</h1>
        <p className="text-slate-600 mt-2">Información de tu cuenta</p>
      </div>

      <div className="card p-8">
        <div className="flex items-center gap-4 mb-6">
          <div className="w-12 h-12 bg-gradient-to-r from-primary-600 to-accent-600 rounded-full flex items-center justify-center">
            <UserIcon className="w-6 h-6 text-white" />
          </div>
          <div>
            <p className="text-sm text-slate-600">Email</p>
            <p className="font-semibold text-slate-900">{userEmail}</p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="p-4 bg-slate-50 rounded-lg">
            <p className="text-xs text-slate-600 font-semibold">PLAN</p>
            <p className="text-lg font-bold text-slate-900 mt-1">
              {userPlan === "FREE" ? "Gratis" : userPlan}
            </p>
          </div>
          <div className="p-4 bg-slate-50 rounded-lg">
            <p className="text-xs text-slate-600 font-semibold">ESTADO</p>
            <p className="text-lg font-bold text-green-600 mt-1">Activo</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProfilePage;
