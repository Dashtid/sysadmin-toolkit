# Server Setup Scripts

Ubuntu server provisioning and maintenance.

## Scripts

| Script | Purpose |
|--------|---------|
| [headless-server-setup.sh](headless-server-setup.sh) | Initial Ubuntu server configuration |
| [ubuntu-server-maintenance.sh](ubuntu-server-maintenance.sh) | Routine maintenance tasks |
| [docker-lab-environment.sh](docker-lab-environment.sh) | Docker and container lab setup |

## Quick Examples

```bash
# Initial server setup
sudo ./headless-server-setup.sh

# Run maintenance
./ubuntu-server-maintenance.sh --updates --cleanup

# Setup Docker lab
sudo ./docker-lab-environment.sh --install
```

---
**Last Updated**: 2025-12-26
