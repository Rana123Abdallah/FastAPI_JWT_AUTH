"""alter column gender2

Revision ID: 70c26548bf1f
Revises: 29c72e4393b1
Create Date: 2023-04-01 00:14:05.801593

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '70c26548bf1f'
down_revision = '29c72e4393b1'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        'Patient',
        sa.Column('gender',sa.String(20),unique= False ,nullable=False),
        
    )



def downgrade() -> None:
    op.drop_column('gender')
