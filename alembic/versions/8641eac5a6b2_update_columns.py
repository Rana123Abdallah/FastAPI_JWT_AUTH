"""update columns

Revision ID: 8641eac5a6b2
Revises: 57c73651c293
Create Date: 2023-03-17 00:58:54.763115

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8641eac5a6b2'
down_revision = '57c73651c293'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.update_table(
        'User',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('username', sa.String(50), nullable=False),
        sa.Column('email', sa.String(200),unique=True, nullable=False),
        sa.Column('password',sa.String(),nullable=False)
    )


def downgrade() -> None:
    pass
