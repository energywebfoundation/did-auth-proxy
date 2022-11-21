module.exports = {
  branches: [
    {
      name: 'release',
      channel: 'latest',
    },
    {
      name: 'develop',
      prerelease: 'alpha',
      channel: 'canary',
    },
  ],
  repositoryUrl: 'git@github.com:energywebfoundation/did-auth-proxy.git',
  extends: '@energyweb/semantic-release-config',
};
