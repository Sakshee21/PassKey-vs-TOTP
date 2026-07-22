"""passkey credential: replace device_type with resident_key_policy, is_discoverable, backup flags, device_name

Revision ID: 6c98170fa606
Revises: 66b6b3289296
Create Date: 2026-07-21 22:43:47.517706

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '6c98170fa606'
down_revision: Union[str, None] = '66b6b3289296'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Manually adjusted: added server_defaults so existing rows (registered
    # under the old device_type-inference logic, whose true resident-key
    # policy we never actually recorded) backfill to honest "we don't know,
    # it defaulted to preferred/not-confirmed" values rather than failing the
    # NOT NULL constraint. All new rows always pass explicit values.
    op.add_column(
        'passkey_credentials',
        sa.Column('resident_key_policy', sa.String(length=20), nullable=False, server_default='preferred'),
    )
    op.add_column(
        'passkey_credentials',
        sa.Column('is_discoverable', sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        'passkey_credentials',
        sa.Column('backup_eligible', sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        'passkey_credentials',
        sa.Column('backup_state', sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column('passkey_credentials', sa.Column('device_name', sa.String(length=128), nullable=True))
    op.drop_column('passkey_credentials', 'device_type')


def downgrade() -> None:
    # create_type=False: the 'device_type' enum TYPE itself was never dropped
    # by upgrade() (only the column was), so it still exists in the database.
    op.add_column(
        'passkey_credentials',
        sa.Column(
            'device_type',
            postgresql.ENUM('RESIDENT', 'NON_RESIDENT', name='device_type', create_type=False),
            autoincrement=False,
            nullable=False,
            server_default='NON_RESIDENT',
        ),
    )
    op.alter_column('passkey_credentials', 'device_type', server_default=None)
    op.drop_column('passkey_credentials', 'device_name')
    op.drop_column('passkey_credentials', 'backup_state')
    op.drop_column('passkey_credentials', 'backup_eligible')
    op.drop_column('passkey_credentials', 'is_discoverable')
    op.drop_column('passkey_credentials', 'resident_key_policy')
