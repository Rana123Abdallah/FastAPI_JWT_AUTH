"""alter column submited at

Revision ID: 00e83ebe1dc1
Revises: 05e464628434
Create Date: 2023-03-31 23:49:04.259422

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '00e83ebe1dc1'
down_revision = '05e464628434'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        'Patient',
        sa.Column('submited_at',sa.DateTime(timezone=True), server_default=sa.func.now())
        
    )



def downgrade() -> None:
    op.drop_column('submited_at')
