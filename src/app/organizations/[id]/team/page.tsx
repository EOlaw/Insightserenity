// src/app/organizations/[id]/team/page.tsx
'use client';

import { useParams } from 'next/navigation';
import { OrganizationsProvider } from '@/hooks/useOrganizations';
import { TeamManagement } from '@/components/organizations/TeamManagement';
import Layout from '@/components/Layout';

export default function TeamManagementPage() {
  const params = useParams();
  const organizationId = params.id as string;

  return (
    <OrganizationsProvider>
      <Layout
        title="Team Management"
        showBackButton={true}
        backUrl={`/organizations/${organizationId}`}
        requireAuth={true}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <TeamManagement organizationId={organizationId} />
        </div>
      </Layout>
    </OrganizationsProvider>
  );
}