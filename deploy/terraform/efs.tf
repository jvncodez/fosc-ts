# Estado persistente — SENTINELA_HOME=/data em EFS. Runs, trilha de auditoria,
# conhecimento e PoCs sobrevivem ao fim da task.

resource "aws_efs_file_system" "state" {
  creation_token = "${local.name}-state"
  encrypted      = true

  tags = { Name = "${local.name}-state" }
}

resource "aws_efs_mount_target" "state" {
  for_each        = toset(var.private_subnet_ids)
  file_system_id  = aws_efs_file_system.state.id
  subnet_id       = each.value
  security_groups = [aws_security_group.efs.id]
}

# Access point: uid/gid 1000 (o usuário do container), diretório /sentinela.
resource "aws_efs_access_point" "state" {
  file_system_id = aws_efs_file_system.state.id

  posix_user {
    uid = 1000
    gid = 1000
  }

  root_directory {
    path = "/sentinela"
    creation_info {
      owner_uid   = 1000
      owner_gid   = 1000
      permissions = "0755"
    }
  }

  tags = { Name = "${local.name}-ap" }
}
