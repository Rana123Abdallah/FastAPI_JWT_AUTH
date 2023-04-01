"""alter column gender

Revision ID: 29c72e4393b1
Revises: 00e83ebe1dc1
Create Date: 2023-03-31 23:57:21.502256

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '29c72e4393b1'
down_revision = '00e83ebe1dc1'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        'Patient',
        sa.Column('gender',sa.String(20),unique= False ,nullable=False),
        
    )


def downgrade() -> None:
    op.drop_column('gender')
