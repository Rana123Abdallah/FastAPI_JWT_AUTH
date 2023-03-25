"""update column

Revision ID: 9ed1e1b6b49f
Revises: ee049b194970
Create Date: 2023-03-19 17:59:11.097589

"""
from sqlalchemy import Column, DateTime,func
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '9ed1e1b6b49f'
down_revision = 'ee049b194970'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        'Codes',
        sa.Column('expired_in',sa.DateTime(timezone=True), server_default=func.now())
        
    )



def downgrade() -> None:
    pass
