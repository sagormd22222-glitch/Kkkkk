// PM2 Production Process Manager Configuration for 24/7 Continuous API Availability
module.exports = {
  apps: [
    {
      name: 'kavo-api',
      script: 'server.ts',
      interpreter: 'node',
      interpreter_args: '--import tsx',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      max_memory_restart: '800M',
      restart_delay: 2000,
      max_restarts: 100,
      min_uptime: '10s',
      kill_timeout: 5000,
      env: {
        NODE_ENV: 'production',
        PORT: 3000
      },
      env_development: {
        NODE_ENV: 'development',
        PORT: 3000
      }
    }
  ]
};
