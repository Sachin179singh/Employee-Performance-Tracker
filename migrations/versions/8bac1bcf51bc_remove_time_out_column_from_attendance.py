"""Remove time_out column from attendance

Revision ID: 8bac1bcf51bc
Revises: 
Create Date: 2025-04-25 18:06:45.641317

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8bac1bcf51bc'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('attendance', schema=None) as batch_op:
        batch_op.drop_column('time_out')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('attendance', schema=None) as batch_op:
        batch_op.add_column(sa.Column('time_out', sa.TIME(), nullable=True))

    # ### end Alembic commands ###
