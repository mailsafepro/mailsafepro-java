import { memo } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { formatPlanName, getStatusColor, translateStatus } from '../utils/profile.utils';
import { ProfileHeader } from '../components/profile/ProfileHeader';
import { InfoCard } from '../components/profile/InfoCard';

/**
 * Encabezado de la página de perfil
 */
const PageHeader = memo(() => (
  <div>
    <h1 className="text-3xl font-bold text-gray-900">Perfil</h1>
    <p className="text-gray-600 mt-2">Información de tu cuenta</p>
  </div>
));

PageHeader.displayName = 'PageHeader';

/**
 * Página de perfil de usuario para MailSafePro
 * Muestra información básica del usuario como email, plan y estado
 */
const ProfilePage = () => {
  const { userEmail, userPlan } = useAuth();

  const formattedPlan = formatPlanName(userPlan);
  const accountStatus = translateStatus('active');
  const statusColor = getStatusColor('active');

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-3xl mx-auto space-y-6">
        <PageHeader />

        <div className="bg-white rounded-lg shadow-md border border-gray-200 p-8">
          <ProfileHeader email={userEmail} />

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <InfoCard
              label="Plan"
              value={formattedPlan}
            />
            <InfoCard
              label="Estado"
              value={accountStatus}
              valueColor={statusColor}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default memo(ProfilePage);
