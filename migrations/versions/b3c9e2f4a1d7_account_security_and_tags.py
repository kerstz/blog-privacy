"""account security (session version, 2FA recovery codes) + categories and tags

Revision ID: b3c9e2f4a1d7
Revises: 618188b0f4dd
Create Date: 2026-09-24 14:00:00

"""
from alembic import op
import sqlalchemy as sa


revision = 'b3c9e2f4a1d7'
down_revision = '618188b0f4dd'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('recovery_codes', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('session_version', sa.Integer(), nullable=False, server_default='0'))

    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.add_column(sa.Column('category', sa.String(length=60), nullable=True))
        batch_op.create_index(batch_op.f('ix_post_category'), ['category'], unique=False)

    op.create_table('tag',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=40), nullable=False),
        sa.Column('slug', sa.String(length=50), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    with op.batch_alter_table('tag', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_tag_slug'), ['slug'], unique=True)

    op.create_table('post_tags',
        sa.Column('post_id', sa.Integer(), nullable=False),
        sa.Column('tag_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['post_id'], ['post.id'], ),
        sa.ForeignKeyConstraint(['tag_id'], ['tag.id'], ),
        sa.PrimaryKeyConstraint('post_id', 'tag_id'),
    )


def downgrade():
    op.drop_table('post_tags')
    with op.batch_alter_table('tag', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_tag_slug'))
    op.drop_table('tag')
    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_post_category'))
        batch_op.drop_column('category')
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('session_version')
        batch_op.drop_column('recovery_codes')
