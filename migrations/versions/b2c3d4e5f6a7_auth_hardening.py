"""Auth hardening: TOTP replay counter, wider TOTP secret

L'invalidation des sessions repose sur `user.session_version`
(migration b3c9e2f4a1d7) : il n'y a plus de colonne `session_token`.

Les secrets TOTP existants (en clair) restent lisibles : ils sont rechiffres
a leur prochaine verification reussie, pas par cette migration.

Revision ID: b2c3d4e5f6a7
Revises: c3d4e5f6a7b8
Create Date: 2026-10-12 12:10:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b2c3d4e5f6a7'
down_revision = 'c3d4e5f6a7b8'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('totp_last_counter', sa.Integer(), nullable=True))
        batch_op.alter_column('totp_secret',
                              existing_type=sa.String(length=64),
                              type_=sa.String(length=255),
                              existing_nullable=True)


def downgrade():
    # Un secret chiffre (> 64 caracteres) n'est plus lisible une fois la
    # colonne retrecie : on desactive la 2FA des comptes concernes plutot que
    # de laisser un secret tronque, qui verrouillerait le compte.
    op.execute("UPDATE \"user\" SET totp_enabled = 0, totp_secret = NULL "
               "WHERE totp_secret IS NOT NULL AND length(totp_secret) > 64")
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('totp_secret',
                              existing_type=sa.String(length=255),
                              type_=sa.String(length=64),
                              existing_nullable=True)
        batch_op.drop_column('totp_last_counter')
