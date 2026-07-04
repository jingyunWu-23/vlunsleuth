import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'Login',
      component: () => import('@/views/LoginView.vue'),
      meta: { requiresAuth: false },
    },
    {
      path: '/register',
      name: 'Register',
      component: () => import('@/views/RegisterView.vue'),
      meta: { requiresAuth: false },
    },
    {
      path: '/',
      component: () => import('@/components/layout/MainLayout.vue'),
      meta: { requiresAuth: true },
      children: [
        {
          path: '',
          name: 'Dashboard',
          component: () => import('@/views/DashboardView.vue'),
        },
        {
          path: 'audit/:taskId',
          name: 'AuditDetail',
          component: () => import('@/views/AuditDetailView.vue'),
        },
        {
          path: 'cross-contract',
          name: 'CrossContract',
          component: () => import('@/views/CrossContractView.vue'),
        },
        {
          path: 'risk-ranking',
          name: 'FunctionRiskRanking',
          component: () => import('@/views/FunctionRiskRankingView.vue'),
        },
        {
          path: 'repair',
          name: 'RepairSuggestions',
          component: () => import('@/views/RepairSuggestionsView.vue'),
        },
        {
          path: 'tasks',
          name: 'TaskHistory',
          component: () => import('@/views/TaskHistoryView.vue'),
        },
        {
          path: 'report/:taskId?',
          name: 'Report',
          component: () => import('@/views/ReportView.vue'),
        },
      ],
    },
    {
      path: '/:pathMatch(.*)*',
      redirect: '/',
    },
  ],
})

router.beforeEach((to, _from, next) => {
  const token = localStorage.getItem('access_token')
  if (to.meta.requiresAuth !== false && !token) {
    next('/login')
  } else if (to.meta.requiresAuth === false && token) {
    next('/')
  } else {
    next()
  }
})

export default router
