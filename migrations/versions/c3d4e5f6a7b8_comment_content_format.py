"""Comment content format (plain BBCode text vs legacy HTML)

Aucune donnee n'est reecrite : les lignes existantes gardent content_format
NULL et sont assainies a l'affichage (voir app/utils.sanitize_legacy_html).

Revision ID: c3d4e5f6a7b8
Revises: a1b2c3d4e5f6
Create Date: 2026-10-12 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c3d4e5f6a7b8'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('comment', schema=None) as batch_op:
        batch_op.add_column(sa.Column('content_format', sa.String(length=10), nullable=True))


def downgrade():
    with op.batch_alter_table('comment', schema=None) as batch_op:
        batch_op.drop_column('content_format')
