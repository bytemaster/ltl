#include <ltl/asset.hpp>
#include <ltl/identity.hpp>
#include <ltl/account.hpp>
#include <ltl/transaction.hpp>

namespace ltl {

      template<typename Action>
      void identity::persist( Action& a ) {
        dbo::id( a, db_id, "id" );
        dbo::field( a, name,       "name"       );
        dbo::field( a, date,       "date"       );
        dbo::field( a, nonce,      "nonce"      );
        dbo::field( a, properties, "properties" );
        dbo::field( a, id_sig,     "id_sig"     );
        dbo::field( a, pub_key,    "pub_key"    );

        dbo::hasMany( a, priv_key, dbo::ManyToOne, "priv_key" );
        dbo::hasMany( a, accounts, dbo::ManyToOne, "owner" );
        dbo::hasMany( a, issued_notes, dbo::ManyToOne, "issued_notes" );
      }

      template<typename Action>
      void private_identity::persist( Action& a ) {
        dbo::id( a, public_identity, "public_identity" );
        dbo::field( a, priv_key, "priv_key" );
        dbo::belongsTo( a, public_identity, "priv_key", dbo::NotNull );
      }

      template<typename Action>
      void asset::persist( Action& a ) {
        dbo::id( a, id, "id" );
        dbo::field( a, m_name, "name" );
        dbo::field( a, m_properties, "properties" );

        dbo::hasMany( a, issuers, dbo::ManyToOne, "issuer" );
      }

      template<typename Action>
      void asset_note::persist( Action& a ) {
        dbo::id(    a, m_id,             "id"         );
        dbo::field( a, m_name,           "name"       );
        dbo::field( a, m_properties,     "properties" );
        dbo::field( a, m_issuer_sig,     "issuer_sig" );

        dbo::belongsTo( a, m_asset_type, "type"       );
        dbo::belongsTo( a, m_issuer,     "issuer"     );
      }


      template<typename Action>
      void account::persist( Action& a ) {
        dbo::id( a, m_id, "id" );
        dbo::field( a, m_balance, "balance" );
        dbo::field( a, m_date, "date" );
        dbo::field( a, m_sig_nums, "sig_nums" );
        dbo::field( a, m_new_sig_nums, "new_sig_nums" );

        dbo::belongsTo( a, m_owner, "owner", dbo::OnDeleteSetNull );
        dbo::belongsTo( a, m_type,  "type",  dbo::OnDeleteSetNull );
        dbo::belongsTo( a, m_host,  "host",  dbo::OnDeleteSetNull );
        dbo::hasMany( a, m_in_box,  dbo::ManyToMany, "in_box" );
        dbo::hasMany( a, m_out_box, dbo::ManyToMany, "out_box" );
        dbo::hasMany( a, m_applied, dbo::ManyToMany, "applied" );
      }

      template<typename Action>
      void transaction::persist( Action& a ) {
        dbo::id( a, m_id, "id" );
        dbo::field( a, m_trx_date, "date" );
        dbo::field( a, m_description, "description" );
        dbo::field( a, m_json_actions, "actions" );
        dbo::field( a, m_json_signatures, "signatures" );
        dbo::field( a, m_host_note, "host_note" );
        dbo::field( a, m_host_signature, "host_signature" );
        dbo::hasMany( a, m_ref_in_accounts, dbo::ManyToMany, "in_box" );
        dbo::hasMany( a, m_ref_out_accounts, dbo::ManyToMany, "out_box" );
        dbo::hasMany( a, m_ref_applied_accounts, dbo::ManyToMany, "applied" );
      }

}
