"""create user table

Revision ID: 57c73651c293
Revises: 
Create Date: 2023-03-09 17:19:49.108976

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '57c73651c293'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'User',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('username', sa.String(50), nullable=False),
        sa.Column('email', sa.String(200),unique=True, nullable=False),
        sa.Column('password',sa.String(50),nullable=False)
    )


def downgrade() -> None:
    op.drop_table('User')
