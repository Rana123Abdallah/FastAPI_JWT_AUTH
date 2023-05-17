"""drop_table_profiledata

Revision ID: c68f018761bf
Revises: 0cc500776eef
Create Date: 2023-05-12 16:45:32.167998

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c68f018761bf'
down_revision = '0cc500776eef'
branch_labels = None
depends_on = None


def upgrade() -> None:
     op.drop_table('profiledata')


def downgrade() -> None:
    pass
