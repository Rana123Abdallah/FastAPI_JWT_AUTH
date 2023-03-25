"""add column in  patient table

Revision ID: 05e464628434
Revises: 965f27ef4d7d
Create Date: 2023-03-24 15:20:10.347052

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '05e464628434'
down_revision = '965f27ef4d7d'
branch_labels = None
depends_on = None


def upgrade() -> None:
   op.add_column('Patient', sa.Column('mobile_number', sa.String))

def downgrade() -> None:
    op.drop_column('Patient', 'mobile_number')
