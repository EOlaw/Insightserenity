// src/app/organizations/[id]/page.tsx
'use client';

import { useParams } from 'next/navigation';
import { OrganizationsProvider } from '@/hooks/useOrganizations';
import { OrganizationDetail } from '@/components/organizations/OrganizationDetail';
import Layout from '@/components/Layout';

export default function OrganizationDetailPage() {
  const params = useParams();
  const organizationId = params.id as string;

  return (
    <OrganizationsProvider>
      <Layout
        title="Organization Details"
        showBackButton={true}
        backUrl="/organizations"
        requireAuth={true}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <OrganizationDetail organizationId={organizationId} />
        </div>
      </Layout>
    </OrganizationsProvider>
  );
}