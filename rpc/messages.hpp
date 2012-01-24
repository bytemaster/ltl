#ifndef LTL_RPC_MESSAGES_HPP_
#define LTL_RPC_MESSAGES_HPP_
#include <string>
#include <boost/optional.hpp>
#include <stdint.h>
#include <vector>


namespace ltl { namespace rpc { 
  /**
   *  These types are used as parameters to 
   *  make the json more self-descriptive and give
   *  it named and optional parameters.
   *
   */
  namespace msg {

    struct allocate_signatures {
      std::string account_id;
      uint32_t    count;
    };

    struct create_account {
        std::string owner_id;
        std::string asset_note_id;
    };

    struct sign_transaction {
      std::string     transaction_id;
      signature_line  sig;
    };

    struct balance_agreement {
      std::string              account_id;
      std::string              owner_signature;
      uint64_t                 new_date;

      // these fields are optional and are only used to detect where
      // there may be a disagreement
      boost::optional<int64_t>                  new_balance;
      boost::optional<std::vector<uint64_t> >   open_sig_ids;
      boost::optional<std::vector<uint64_t> >   open_new_sig_ids;
    };
    struct balance_agreement_reply {
      std::string                  status;
      boost::optional<std::string> server_account_signature;
    };

    /**
     *  To request the account requires that the current date
     *  be signed with the private key of the account or that
     *  the account is an issuer's account which must be public
     *  information for proper audits.
     */
    struct account_request {
      std::string account_id;
      boost::optional<uint64_t>    date;
      boost::optional<std::string> signature;
    };

} } } // ltl::rpc::msg


#endif // LTL_RPC_MESSAGES_HPP_
