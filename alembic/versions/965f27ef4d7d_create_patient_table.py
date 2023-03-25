"""create patient table

Revision ID: 965f27ef4d7d
Revises: 9ed1e1b6b49f
Create Date: 2023-03-24 14:12:45.052744

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '965f27ef4d7d'
down_revision = '9ed1e1b6b49f'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'Patient',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('full_name', sa.String(50), nullable=False),
        sa.Column('gender', sa.String(20),unique=True, nullable=False),
        sa.Column('address',sa.String(200),nullable=False),
        sa.Column('submited_at',sa.TIMESTAMP)
    )



def downgrade() -> None:
    op.drop_table('Patient')
