"""Site text revisions and author

Revision ID: a1b2c3d4e5f6
Revises: 4bb193de97b6
Create Date: 2026-10-12 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = '4bb193de97b6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'site_text_revision',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('key', sa.String(length=120), nullable=False),
        sa.Column('text_en', sa.Text(), nullable=True),
        sa.Column('text_fr', sa.Text(), nullable=True),
        sa.Column('action', sa.String(length=16), nullable=False),
        sa.Column('changed_by_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['changed_by_id'], ['user.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('site_text_revision', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_site_text_revision_key'), ['key'], unique=False)
        batch_op.create_index(batch_op.f('ix_site_text_revision_created_at'), ['created_at'], unique=False)

    # batch obligatoire : SQLite ne sait pas ajouter une cle etrangere seul.
    with op.batch_alter_table('site_text', schema=None) as batch_op:
        batch_op.add_column(sa.Column('updated_by_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key('fk_site_text_updated_by', 'user', ['updated_by_id'], ['id'])


def downgrade():
    with op.batch_alter_table('site_text', schema=None) as batch_op:
        batch_op.drop_constraint('fk_site_text_updated_by', type_='foreignkey')
        batch_op.drop_column('updated_by_id')

    with op.batch_alter_table('site_text_revision', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_site_text_revision_created_at'))
        batch_op.drop_index(batch_op.f('ix_site_text_revision_key'))

    op.drop_table('site_text_revision')
