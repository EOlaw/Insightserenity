// src/app/organizations/page.tsx
'use client';

import { OrganizationsProvider } from '@/hooks/useOrganizations';
import { OrganizationList } from '@/components/organizations/OrganizationList';
import Layout from '@/components/Layout';

export default function OrganizationsPage() {
  return (
    <OrganizationsProvider>
      <Layout
        title="Organizations"
        requireAuth={true}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <OrganizationList />
        </div>
      </Layout>
    </OrganizationsProvider>
  );
}