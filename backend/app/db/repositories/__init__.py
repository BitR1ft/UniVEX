"""
Repository package for database access layer.
Exports all repository classes and the Prisma client dependency.
"""
from app.db.repositories.base import BaseRepository
from app.db.repositories.users_repo import UsersRepository
from app.db.repositories.projects_repo import ProjectsRepository
from app.db.repositories.tasks_repo import TasksRepository
from app.db.repositories.sessions_repo import SessionsRepository

__all__ = [
    "BaseRepository",
    "UsersRepository",
    "ProjectsRepository",
    "TasksRepository",
    "SessionsRepository",
]
