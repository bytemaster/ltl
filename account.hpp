#ifndef _LTL_ACCOUNT_HPP_
#define _LTL_ACCOUNT_HPP_
#include <ltl/dbo_traits.hpp>
#include <ltl/crypto.hpp>
#include <stdint.h>
#include <vector>

namespace ltl {

  /**
   *  This class is responsible for persisting account data and
   *  making changes to the account.  Its primary job is to 
   *  maintain invariants around the account state and calculating
   *  derived properties from the account state.
   */
  class account : public dbo::Dbo<account>, public dbo::ptr<account> {
    public:
      typedef dbo::collection<dbo::ptr<transaction> > trx_collection;
      typedef std::map<sha1, dbo::ptr<transaction> > mtrx_map;

      account(){}
      account( const dbo::ptr<identity>& host,
               const dbo::ptr<identity>& owner,
               const dbo::ptr<asset_note>& type,
               uint64_t init_date );

      std::string to_string()const;

      const sha1&               get_id()const;
      const signature&          owner_signature()const;
      const signature&          host_signature()const;

      const dbo::ptr<identity>&   owner()const;
      const dbo::ptr<identity>&   host()const;
      const dbo::ptr<asset_note>& type()const;

      // balance after all applied and/or out box transactions
      int64_t                get_applied_balance()const;
      int64_t                get_pending_balance()const;

      int64_t                   balance()const;
      boost::posix_time::ptime  balance_date()const;

      const trx_collection&  get_applied_transactions()const { return m_applied; }

      /**
       * Signature IDs are used to determine which signatures
       * are valid.  Each signature number may only be used once
       * and is then removed from the balance agreement after
       * the transaction it was applied to has been cleared.
       */
      ///@{
      const std::vector<uint64_t>& sig_ids()const;
      const std::vector<uint64_t>& new_sig_ids()const;
      std::vector<uint64_t>        find_used_sig_ids()const;
      std::vector<uint64_t>        find_unused_sig_ids()const;
      ///@}
      
      bool is_valid()const;
      bool owner_signed()const;
      bool host_signed()const;

      sha1 get_digest()const;
      sha1 get_applied_digest()const;

      template<typename Action>
      void persist( Action& a );

      void get_accept_balance_digest(  const boost::posix_time::ptime& time, 
                                     const std::vector<uint64_t>& new_sig_nums, 
                                     const std::vector<sha1>& applied_trx_ids,
                                     int64_t& newbal, sha1& digest, 
                                     std::set<uint64_t>& open_sig_ids, 
                                     std::vector<uint64_t>& open_new_sig_ids,
                                     mtrx_map& mtrx )const;

      void host_accept_balance( const signature& owner_sig, int64_t new_bal, const boost::posix_time::ptime& time, 
                           const std::vector<uint64_t>& new_sig_nums, 
                           const std::vector<sha1>& applied_trx_ids );

      void owner_accept_balance( const signature& owner_sig, const signature& server_sig,
                                 int64_t new_bal, const boost::posix_time::ptime& time, 
                                 const std::vector<uint64_t>& new_sig_nums, 
                                 const std::vector<sha1>& applied_trx_ids );

      void allocate_signature_numbers( const std::vector<uint64_t>& signums, 
                                       const signature& host_sig );

    private:
      void    set_signature( std::string&, const signature& sig );
      mutable boost::optional<sha1>                    m_oid;
      mutable boost::optional<signature>               m_oowner_sig;
      mutable boost::optional<signature>               m_ohost_sig;
      mutable boost::optional<std::vector<uint64_t> >  m_osig_ids;
      mutable boost::optional<std::vector<uint64_t> >  m_onew_sig_ids;


      trx_collection m_in_box;
      trx_collection m_out_box;
      trx_collection m_applied;

      // primary key sha1( host, owner, type )
      std::string           m_id;

      dbo::ptr<identity>    m_host;
      dbo::ptr<identity>    m_owner;
      dbo::ptr<asset_note>  m_type;

      long long             m_balance;
      long long             m_date;
      std::string           m_sig_nums;         // base64( std::vector<uint64_t> )
      std::string           m_new_sig_nums; // base64( std::vector<uint64_t> )

      // owner.sign( sha1( json(owner.id, asset.id, host.id, balance, date, sig_num) ), owner_sig )
      std::string           m_owner_sig; // base64( signature )

      // host.sign( sha1( owner_sig ) , host_sig )
      std::string           m_host_sig;  // base64( signature )

  };


} // namespace ltl


#endif
