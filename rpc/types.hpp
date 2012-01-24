#ifndef _LTL_RPC_TYPES_HPP_
#define _LTL_RPC_TYPES_HPP_
#include <string>
#include <boost/optional.hpp>
#include <stdint.h>
#include <vector>
#include <json/value.hpp>

namespace ltl { namespace rpc {

  /**
   *  An identity contains all information necessary
   *  to document a user.  Identities are uniquely identified
   *  by the sha1(public key).  All other information is
   *  is arbitrary, but is signed by the private key.
   *
   *  Each identity may be vouched for by other identities
   *  and these vouchers establish a web-of trust among
   *  identities.  
   *
   *  Each identity also has a rank established by its nonce. 
   *  the lower the value of sha1(nonce+signature) the higher the 
   *  rank.  The rank represents CPU hours invested into
   *  the identity.  
   *
   *  Changing any properties of the identity resets the
   *  nonce and all vouchers.
   *
   *  A graph algorithm can establish the net weight for
   *  an unknown identity using the ranks + trust values.
   *
   *  Combined this information can help users make informed
   *  decisions about the trust of anonymous users.
   */
  struct identity {
      std::string   id;
      std::string   pub_key;
      std::string   name;
      uint64_t      date;
      std::string   properties;
      std::string   signature;  // sign( sha1(pub_key,name,date,properties) )

      boost::optional<uint64_t>                   nonce;
      boost::optional< std::vector<std::string> > vouchers;
  };

  /**
   *  A voucher is where one id vouches for the
   *  trust in another.
   */
  struct voucher {
    std::string identity_id;
    int32_t     trust;
    std::string voucher_identity_id;
    std::string voucher_signature;
  };

  /**
   *  An asset is a complete description of a unique item. 
   *
   *  Examples:  1 oz round of .999 silver (any coin meeting those specs)
   *             1 oz US Silver Eagle of .999 silver (any coin meeting those specs)
   *             1 oz US Silver Eagle of .999 silver 1995  // specifically 1995
   *             Parking at 11:15AM in XYZ Parking Lot
   *    
   *  Most of the information is carried in the properties which could be any
   *  kind of document, json, xml, html, etc.  An asset describes the deliverable and
   *  may 'inherit' other asset types or contain other asset types (baskets).
   *
   *  More work will need to be put into specifying this structure of information.
   */
  struct asset {
      asset( const std::string& _name, const std::string& _props );
      asset(){}

      boost::optional<std::string> id; // derived from name/properties
      std::string                  name;
      std::string                  properties;
  };

  /**
   *  An asset note is a promise to provide the specified asset 
   *  under specific terms outlined in the properties.  Terms may include
   *  'where', 'when', expiration date, contact information, legal requirements,
   *  arbitration, etc.
   */
  struct asset_note {
      std::string id;
      std::string asset_id;
      std::string issuer_id;
      std::string name;
      std::string properties;
      std::string issuer_sig;
  };

  /**
   *  A signature line specifies specific information regarding
   *  the signature including any extra meta-information regarding
   *  the nature of the signature. Such as 'accepted', 'rejected',
   *  'under duress' 
   */
  struct signature_line {
    std::string                  account_id;
    boost::optional<uint64_t>    date;
    boost::optional<uint64_t>    sig_num;
    boost::optional<std::string> state;
    boost::optional<std::string> note;
    boost::optional<std::string> sig; // base64 encoded
  };

  /**
   *  A transaction is an atomic operation that the server
   *  performs to update multiple accounts at once.  This facilitates
   *  trade.
   */
  struct transaction {
      std::string                                    id;
      uint64_t                                       date;
      std::string                                    description;
      std::vector<json::value>                       actions; 
      boost::optional<std::vector<signature_line> >  signatures;
      boost::optional<std::string>                   host_note;
      boost::optional<std::string>                   host_sig;
  };

  /**
   *  An account contains the current state of an account 
   *  including all open transactions.
   */
  struct account {
      std::string           id;
      std::string           host_id;
      std::string           owner_id;
      std::string           asset_note_id;
      uint64_t              date;
      int64_t               balance;      
      std::vector<uint64_t> sig_nums;
      std::vector<uint64_t> new_sig_nums;
      std::string           owner_sig;
      std::string           server_sig;

      std::vector<std::string> in_box;
      std::vector<std::string> out_box;
      std::vector<std::string> applied;
  };

  /**
   *  An offer to exchange one asset for another
   *  at a specified rate.
   *
   */
  struct market_offer {
      std::string id;
      std::string buy_asset_id;
      std::string sell_asset_id;
      int64_t     buy_count;
      int64_t     max_price; // per item
      int64_t     min_size;  // minimum order amount
      int64_t     start_date;
      int64_t     expire_date;
  };

} } 

#endif
