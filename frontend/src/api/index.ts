import apiClient from './client'
import type {
  AuthResponse,
  LoginRequest,
  RegisterRequest,
  AuditTask,
  AuditTaskListResponse,
  AuditReport,
  TaskEvent,
  HealthResponse,
  User,
} from '@/types'

// ========== Auth ==========
export const authApi = {
  login(data: LoginRequest) {
    return apiClient.post<AuthResponse>('/auth/login', data)
  },
  register(data: RegisterRequest) {
    return apiClient.post<AuthResponse>('/auth/register', data)
  },
  me() {
    return apiClient.get<User>('/auth/me')
  },
  logout() {
    return apiClient.post('/auth/logout')
  },
}

// ========== Health ==========
export const healthApi = {
  check() {
    return apiClient.get<HealthResponse>('/health')
  },
}

// ========== Audits ==========
export const auditsApi = {
  list(params?: { status?: string; limit?: number; offset?: number }) {
    return apiClient.get<AuditTaskListResponse>('/audits', { params })
  },

  get(taskId: string) {
    return apiClient.get<AuditTask>(`/audits/${taskId}`)
  },

  create(data: FormData) {
    return apiClient.post<AuditTask>('/audits/upload', data, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
  },

  getEvents(taskId: string) {
    return apiClient.get<TaskEvent[]>(`/audits/${taskId}/events`)
  },

  cancel(taskId: string) {
    return apiClient.post(`/audits/${taskId}/cancel`)
  },

  retry(taskId: string, asyncRun = true) {
    return apiClient.post<AuditTask>(`/audits/${taskId}/retry`, { async_run: asyncRun })
  },

  delete(taskId: string, deleteUpload = false) {
    return apiClient.delete(`/audits/${taskId}`, {
      params: { delete_upload: deleteUpload },
    })
  },
}

// ========== Reports ==========
export const reportsApi = {
  getReport(taskId: string) {
    return apiClient.get<AuditReport>(`/audits/${taskId}/report`)
  },

  getReportJson(taskId: string) {
    return apiClient.get(`/audits/${taskId}/report.json`)
  },

  getReportMarkdown(taskId: string) {
    return apiClient.get(`/audits/${taskId}/report.md`, {
      responseType: 'text',
    })
  },

  getArtifacts(taskId: string) {
    return apiClient.get(`/audits/${taskId}/artifacts`)
  },
}
