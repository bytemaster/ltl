#ifndef _LTL_TRANSACTION_HPP_
#define _LTL_TRANSACTION_HPP_
#include <ltl/account.hpp>
#include <ltl/action.hpp>
#include <json/value.hpp>
#include <stdint.h>
#include <ltl/crypto.hpp>
#include <Wt/Dbo/Dbo>

namespace ltl {

  struct signature_line {
    sha1                         account_id;
    boost::optional<uint64_t>    date;
    boost::optional<uint64_t>    sig_num;
    boost::optional<std::string> state;
    boost::optional<std::string> note;
    boost::optional<signature>   sig;
  };
  json::value&       operator<<(json::value& v, const signature_line& s );
  const json::value& operator>>(const json::value& v, signature_line& s );

  /**
   *  A transaction is a set of actions that must be 
   *  performed atomicly.  Each action may require a 
   *  signature before it may be applied.
   *
   *  A transaction is defined by a JSON object of the form
   *
   *  {
   *      "date" : utc ms
   *      "actions" : [
   *        { "type"      : "transfer"
   *          "data" : {
   *              "from"      : "account_id"
   *              "to"        : "account_id"
   *              "amount"    : 1234
   *          }
   *        },
   *        { "type"      : "message"
   *          "data"      : {
   *              "to"        : "account_id"
   *               "message"   : "Encrypted with to public key"
   *          }
   *        }
   *      ]
   *      "signatures" : [
   *        { "id": "account_id",
   *          "num": SIG_NUM 
   *          "state": "Accepted",
   *          "note": {}, 
   *          "signature": "signature" -> sign( sha1( date + actions + num + state + params ) )
   *        },
   *      ]
   *      "host_note"      : "Accepted", "Invalid", "Pending", etc..
   *      "host_signature" : "signature" -> sign( date + actions + signatures + host_note )
   *  }
   *
   *  A transaction processes all actions and builds a list of accounts that must sign before
   *  the transaction can be affirmed by the server. The server only affirms the transaction 
   *  if all accounts have sufficient funds / permission.
   */
  class transaction : public dbo::Dbo<transaction>, public dbo::ptr<transaction> {
      public:
        const sha1& get_id()const; // sha1( date + actions )
        transaction(){}
        transaction( const std::vector<action::ptr>& acts, const std::string& desc, uint64_t utc_ms = 0 );

        std::vector<sha1> get_required_signatures()const;

        const std::vector<signature_line>& get_signatures()const;
        const std::vector<action::ptr>&    get_actions()const;

        const std::string&        get_description()const;
        boost::posix_time::ptime  get_date()const;

        sha1  get_digest()const;

        bool can_sign()const; 

        /// returns the delta balance of applying this transaction to the given account
        int64_t apply( const sha1& account )const;
        boost::optional<uint64_t> get_signature_num_for( const sha1& account )const;

        bool is_valid()const;
        bool is_signed_by( const sha1& acnt_id )const;
        bool is_signed_all()const;

        template<typename Action>
        void persist( Action& a );

        void update_signature( const signature_line& sig );

        const dbo::collection<dbo::ptr<account> >&  referenced_applied();
        const dbo::collection<dbo::ptr<account> >&  referenced_in_box();
        const dbo::collection<dbo::ptr<account> >&  referenced_out_box();

        void post_to_accounts();
        bool sign_host();

        const std::string& get_host_signature_b64()const;
        const std::string& get_host_note()const;
      private:
        mutable boost::optional<sha1>                         m_oid;
        mutable boost::optional<signature>                    m_ohost_signature;
        mutable boost::optional<std::vector<action::ptr> >    m_actions;
        mutable boost::optional<std::vector<signature_line> > m_signatures;
        dbo::collection<dbo::ptr<account> >                   m_ref_applied_accounts;
        dbo::collection<dbo::ptr<account> >                   m_ref_in_accounts;
        dbo::collection<dbo::ptr<account> >                   m_ref_out_accounts;

        std::string m_id;
        long long   m_trx_date;
        std::string m_description;
        std::string m_json_actions;
        std::string m_json_signatures;
        std::string m_host_note;
        std::string m_host_signature;
  };



}

#endif
