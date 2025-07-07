// src/components/organizations/TeamManagement.tsx
'use client';

import { useEffect, useState } from 'react';
import { useOrganizations } from '@/hooks/useOrganizations';
import { OrganizationMember, OrganizationInvitation } from '@/types/organization';
import { validateEmail } from '@/lib/utils';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';

interface TeamManagementProps {
  organizationId: string;
}

export function TeamManagement({ organizationId }: TeamManagementProps) {
  const {
    currentOrganization,
    members,
    invitations,
    getOrganization,
    getMembers,
    getInvitations,
    inviteMember,
    resendInvitation,
    revokeInvitation,
    updateMemberRole,
    removeMember,
    isLoading,
    error,
    clearError
  } = useOrganizations();

  const [activeTab, setActiveTab] = useState('members');
  const [showInviteForm, setShowInviteForm] = useState(false);
  const [inviteFormData, setInviteFormData] = useState({
    email: '',
    role: 'member',
    permissions: [] as string[]
  });
  const [inviteErrors, setInviteErrors] = useState<Record<string, string>>({});
  const [alertMessage, setAlertMessage] = useState<{ type: 'error' | 'success'; message: string } | null>(null);

  useEffect(() => {
    loadData();
  }, [organizationId]);

  const loadData = async () => {
    try {
      await Promise.all([
        getOrganization(organizationId),
        getMembers(organizationId),
        getInvitations(organizationId)
      ]);
    } catch (error) {
      console.error('Failed to load team data:', error);
    }
  };

  const validateInviteForm = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (!inviteFormData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!validateEmail(inviteFormData.email)) {
      newErrors.email = 'Invalid email format';
    }

    if (!inviteFormData.role) {
      newErrors.role = 'Role is required';
    }

    setInviteErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleInviteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAlertMessage(null);
    clearError();

    if (!validateInviteForm()) return;

    try {
      await inviteMember(organizationId, inviteFormData);
      
      setAlertMessage({
        type: 'success',
        message: `Invitation sent to ${inviteFormData.email}`
      });

      setInviteFormData({ email: '', role: 'member', permissions: [] });
      setShowInviteForm(false);
      setInviteErrors({});
    } catch (error: any) {
      setAlertMessage({
        type: 'error',
        message: error.message || 'Failed to send invitation'
      });
    }
  };

  const handleResendInvitation = async (invitationId: string, email: string) => {
    try {
      await resendInvitation(organizationId, invitationId);
      setAlertMessage({
        type: 'success',
        message: `Invitation resent to ${email}`
      });
    } catch (error: any) {
      setAlertMessage({
        type: 'error',
        message: error.message || 'Failed to resend invitation'
      });
    }
  };

  const handleRevokeInvitation = async (invitationId: string, email: string) => {
    if (!confirm(`Are you sure you want to revoke the invitation for ${email}?`)) {
      return;
    }

    try {
      await revokeInvitation(organizationId, invitationId);
      setAlertMessage({
        type: 'success',
        message: `Invitation revoked for ${email}`
      });
    } catch (error: any) {
      setAlertMessage({
        type: 'error',
        message: error.message || 'Failed to revoke invitation'
      });
    }
  };

  const handleUpdateMemberRole = async (memberId: string, newRole: string, memberName: string) => {
    try {
      await updateMemberRole(organizationId, memberId, { role: newRole });
      setAlertMessage({
        type: 'success',
        message: `Updated role for ${memberName}`
      });
    } catch (error: any) {
      setAlertMessage({
        type: 'error',
        message: error.message || 'Failed to update member role'
      });
    }
  };

  const handleRemoveMember = async (memberId: string, memberName: string) => {
    if (!confirm(`Are you sure you want to remove ${memberName} from the organization?`)) {
      return;
    }

    try {
      await removeMember(organizationId, memberId);
      setAlertMessage({
        type: 'success',
        message: `${memberName} has been removed from the organization`
      });
    } catch (error: any) {
      setAlertMessage({
        type: 'error',
        message: error.message || 'Failed to remove member'
      });
    }
  };

  const formatInvitationStatus = (status: string) => {
    switch (status) {
      case 'pending': return { text: 'Pending', color: 'text-yellow-600 bg-yellow-100' };
      case 'accepted': return { text: 'Accepted', color: 'text-green-600 bg-green-100' };
      case 'expired': return { text: 'Expired', color: 'text-red-600 bg-red-100' };
      case 'revoked': return { text: 'Revoked', color: 'text-gray-600 bg-gray-100' };
      default: return { text: status, color: 'text-gray-600 bg-gray-100' };
    }
  };

  const formatRole = (role: string) => {
    return role.charAt(0).toUpperCase() + role.slice(1);
  };

  const tabs = [
    { id: 'members', label: 'Members', count: members.length },
    { id: 'invitations', label: 'Invitations', count: invitations.length }
  ];

  const renderMembersTab = () => (
    <div className="space-y-4">
      {/* Owner */}
      {currentOrganization && (
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center">
                  <svg className="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                  </svg>
                </div>
                <div>
                  <p className="font-medium text-gray-900">Organization Owner</p>
                  <p className="text-sm text-gray-600">Full administrative access</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className="px-2 py-1 rounded-full text-xs font-medium text-purple-600 bg-purple-100">
                  Owner
                </span>
                <span className="text-sm text-gray-500">
                  Since {new Date(currentOrganization.createdAt).toLocaleDateString()}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Members List */}
      {members.length === 0 ? (
        <Card>
          <CardContent className="text-center py-8">
            <div className="text-gray-400 mb-4">
              <svg className="w-12 h-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-.5a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
              </svg>
            </div>
            <h3 className="text-lg font-medium text-gray-900 mb-2">No team members yet</h3>
            <p className="text-gray-600 mb-4">Invite people to join your organization</p>
            <Button onClick={() => setShowInviteForm(true)}>
              Invite Team Member
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {members.map((member) => (
            <Card key={member._id}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-gray-100 rounded-full flex items-center justify-center">
                      {member.user.profile?.avatar ? (
                        <img
                          src={member.user.profile.avatar}
                          alt={`${member.user.firstName} ${member.user.lastName}`}
                          className="w-10 h-10 rounded-full object-cover"
                        />
                      ) : (
                        <span className="text-sm font-medium text-gray-600">
                          {member.user.firstName.charAt(0)}{member.user.lastName.charAt(0)}
                        </span>
                      )}
                    </div>
                    <div>
                      <p className="font-medium text-gray-900">
                        {member.user.firstName} {member.user.lastName}
                      </p>
                      <p className="text-sm text-gray-600">{member.user.email}</p>
                      {member.user.profile?.title && (
                        <p className="text-xs text-gray-500">{member.user.profile.title}</p>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <select
                      value={member.role}
                      onChange={(e) => handleUpdateMemberRole(
                        member._id, 
                        e.target.value, 
                        `${member.user.firstName} ${member.user.lastName}`
                      )}
                      className="text-sm border border-gray-300 rounded px-2 py-1"
                    >
                      <option value="member">Member</option>
                      <option value="admin">Admin</option>
                      <option value="manager">Manager</option>
                    </select>
                    <span className="text-xs text-gray-500">
                      Joined {new Date(member.addedAt).toLocaleDateString()}
                    </span>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleRemoveMember(
                        member._id, 
                        `${member.user.firstName} ${member.user.lastName}`
                      )}
                      className="text-red-600 hover:text-red-700"
                    >
                      Remove
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );

  const renderInvitationsTab = () => (
    <div className="space-y-4">
      {invitations.length === 0 ? (
        <Card>
          <CardContent className="text-center py-8">
            <div className="text-gray-400 mb-4">
              <svg className="w-12 h-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
            </div>
            <h3 className="text-lg font-medium text-gray-900 mb-2">No pending invitations</h3>
            <p className="text-gray-600 mb-4">All invitations have been accepted or expired</p>
            <Button onClick={() => setShowInviteForm(true)}>
              Send New Invitation
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {invitations.map((invitation) => {
            const statusInfo = formatInvitationStatus(invitation.status);
            return (
              <Card key={invitation._id}>
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 bg-gray-100 rounded-full flex items-center justify-center">
                        <svg className="w-5 h-5 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                        </svg>
                      </div>
                      <div>
                        <p className="font-medium text-gray-900">{invitation.email}</p>
                        <p className="text-sm text-gray-600">
                          Invited as {formatRole(invitation.role)} by{' '}
                          {invitation.invitedBy.firstName} {invitation.invitedBy.lastName}
                        </p>
                        <p className="text-xs text-gray-500">
                          Sent {new Date(invitation.invitedAt).toLocaleDateString()}
                          {invitation.expiresAt && (
                            <span> • Expires {new Date(invitation.expiresAt).toLocaleDateString()}</span>
                          )}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusInfo.color}`}>
                        {statusInfo.text}
                      </span>
                      {invitation.status === 'pending' && (
                        <div className="flex gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleResendInvitation(invitation._id, invitation.email)}
                          >
                            Resend
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleRevokeInvitation(invitation._id, invitation.email)}
                            className="text-red-600 hover:text-red-700"
                          >
                            Revoke
                          </Button>
                        </div>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );

  const renderInviteForm = () => (
    <Card>
      <CardHeader>
        <CardTitle>Invite Team Member</CardTitle>
        <CardDescription>Send an invitation to join your organization</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleInviteSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Email Address *
            </label>
            <Input
              type="email"
              value={inviteFormData.email}
              onChange={(e) => setInviteFormData(prev => ({ ...prev, email: e.target.value }))}
              error={inviteErrors.email}
              placeholder="colleague@example.com"
              className="w-full"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Role *
            </label>
            <select
              value={inviteFormData.role}
              onChange={(e) => setInviteFormData(prev => ({ ...prev, role: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="member">Member - Basic access</option>
              <option value="admin">Admin - Administrative access</option>
              <option value="manager">Manager - Team management access</option>
            </select>
            {inviteErrors.role && (
              <p className="text-sm text-red-600 mt-1">{inviteErrors.role}</p>
            )}
          </div>

          <div className="flex gap-2 pt-4">
            <Button type="submit" disabled={isLoading}>
              {isLoading ? 'Sending...' : 'Send Invitation'}
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setShowInviteForm(false);
                setInviteFormData({ email: '', role: 'member', permissions: [] });
                setInviteErrors({});
              }}
            >
              Cancel
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );

  if (isLoading && !currentOrganization) {
    return (
      <div className="flex justify-center py-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Team Management</h1>
          <p className="text-gray-600">
            Manage team members and invitations for{' '}
            {currentOrganization?.displayName || currentOrganization?.name || 'your organization'}
          </p>
        </div>
        <Button onClick={() => setShowInviteForm(true)}>
          Invite Team Member
        </Button>
      </div>

      {/* Alert Messages */}
      {(alertMessage || error) && (
        <Alert 
          type={(alertMessage?.type || 'error') as 'error' | 'success'} 
          onClose={() => {
            setAlertMessage(null);
            clearError();
          }}
        >
          {alertMessage?.message || error}
        </Alert>
      )}

      {/* Invite Form */}
      {showInviteForm && renderInviteForm()}

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {tab.label} ({tab.count})
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'members' ? renderMembersTab() : renderInvitationsTab()}
    </div>
  );
}