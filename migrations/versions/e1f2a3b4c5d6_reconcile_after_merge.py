"""Reconcile the schema after merging the two migration histories

The account-security / tags revision (b3c9e2f4a1d7) was applied on some
installations before the local chain (site texts, moderation, auth hardening)
was rebased on top of it. A database that was already at the old local head
(b2c3d4e5f6a7) is considered "up to date" by Alembic without ever having run
b3c9e2f4a1d7: this revision creates, only when missing, what that revision
adds. It is idempotent and does nothing on a database that went through the
whole chain.

Revision ID: e1f2a3b4c5d6
Revises: b2c3d4e5f6a7
Create Date: 2026-10-12 18:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e1f2a3b4c5d6'
down_revision = 'b2c3d4e5f6a7'
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())

    user_cols = {c['name'] for c in inspector.get_columns('user')}
    if 'session_token' in user_cols:
        # Column of the old local chain, replaced by `session_version`.
        with op.batch_alter_table('user', schema=None) as batch_op:
            batch_op.drop_column('session_token')
        user_cols.discard('session_token')
    missing_user = [name for name in ('recovery_codes', 'session_version') if name not in user_cols]
    if missing_user:
        with op.batch_alter_table('user', schema=None) as batch_op:
            if 'recovery_codes' in missing_user:
                batch_op.add_column(sa.Column('recovery_codes', sa.Text(), nullable=True))
            if 'session_version' in missing_user:
                batch_op.add_column(sa.Column('session_version', sa.Integer(), nullable=False,
                                              server_default='0'))

    post_cols = {c['name'] for c in inspector.get_columns('post')}
    post_indexes = {i['name'] for i in inspector.get_indexes('post')}
    if 'category' not in post_cols:
        with op.batch_alter_table('post', schema=None) as batch_op:
            batch_op.add_column(sa.Column('category', sa.String(length=60), nullable=True))
    if 'ix_post_category' not in post_indexes:
        with op.batch_alter_table('post', schema=None) as batch_op:
            batch_op.create_index(batch_op.f('ix_post_category'), ['category'], unique=False)

    if 'tag' not in tables:
        op.create_table('tag',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('name', sa.String(length=40), nullable=False),
            sa.Column('slug', sa.String(length=50), nullable=False),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('name'),
        )
        with op.batch_alter_table('tag', schema=None) as batch_op:
            batch_op.create_index(batch_op.f('ix_tag_slug'), ['slug'], unique=True)

    if 'post_tags' not in tables:
        op.create_table('post_tags',
            sa.Column('post_id', sa.Integer(), nullable=False),
            sa.Column('tag_id', sa.Integer(), nullable=False),
            sa.ForeignKeyConstraint(['post_id'], ['post.id'], ),
            sa.ForeignKeyConstraint(['tag_id'], ['tag.id'], ),
            sa.PrimaryKeyConstraint('post_id', 'tag_id'),
        )


def downgrade():
    # Nothing to undo: the objects created here belong to b3c9e2f4a1d7, whose
    # own downgrade removes them.
    pass
