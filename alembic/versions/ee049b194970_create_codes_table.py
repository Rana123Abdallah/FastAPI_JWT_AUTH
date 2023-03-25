"""create codes table

Revision ID: ee049b194970
Revises: 57c73651c293
Create Date: 2023-03-18 18:12:34.806659

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ee049b194970'
down_revision = '57c73651c293'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'Codes',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('reset_code', sa.String(50), nullable=False),
        sa.Column('email', sa.String(200),unique=True, nullable=False),
        sa.Column('expired_in',sa.DateTime())
    )



def downgrade() -> None:
    op.drop_table('Codes')
