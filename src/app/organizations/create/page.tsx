// src/app/organizations/create/page.tsx
'use client';

import { useRouter } from 'next/navigation';
import { OrganizationsProvider } from '@/hooks/useOrganizations';
import { CreateOrganizationForm } from '@/components/organizations/CreateOrganizationForm';
import Layout from '@/components/Layout';

export default function CreateOrganizationPage() {
  const router = useRouter();

  const handleSuccess = (organizationId: string) => {
    router.push(`/organizations/${organizationId}`);
  };

  const handleCancel = () => {
    router.push('/organizations');
  };

  return (
    <OrganizationsProvider>
      <Layout
        title="Create Organization"
        showBackButton={true}
        backUrl="/organizations"
        requireAuth={true}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <CreateOrganizationForm
            onSuccess={handleSuccess}
            onCancel={handleCancel}
          />
        </div>
      </Layout>
    </OrganizationsProvider>
  );
}