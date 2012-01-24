#ifndef _LTL_MARKET_HPP_
#define _LTL_MARKET_HPP_
#include <ltl/transaction.hpp>

namespace ltl {

  class market_trade;
  class transaction;

  typedef dbo::collection<dbo::ptr<market_trade> > market_trades;

  class market_order : public dbo::Dbo<market_order>, public dbo::ptr<market_order> {
    public:
      enum order_type {
        buy  = 0x01,
        sell = 0x02
      };
      market_order( const dbo::ptr<transaction>& order_trx );
      market_order(){}

      template<typename Action>
      void persist( Action& a );

      dbo::ptr<transaction> order_trx; // primary key, source of authorization for this order
      dbo::ptr<transaction> fill_trx;  // the transaction that holds trades... will change after every trade.
      int                   type;
      std::string           stock_note; 
      std::string           cur_note; 
      long long             num; 
      long long             price; 
      long long             start_date;
      long long             end_date;
      long long             min_unit;

      long long             num_unfilled; // num - sum(trades.num)

      market_trades         buy_trades;
      market_trades         sell_trades;
  };

  class market_trade : public dbo::Dbo<market_trade>, public dbo::ptr<market_trade> {
    public:
      market_trade( const market_order::ptr& b, const market_order::ptr& s );
      market_trade(){}

      template<typename Action>
      void persist( Action& a );

      market_order::ptr    buy_order;
      market_order::ptr    sell_order;
      long long            num;
      long long            price;
      long long            timestamp;
  };
  

  class market {
    public:
      market( dbo::Session& s ); 
      ~market();

      /**
       *  Adds the market order to the session, checks to
       *  see if it allows any orders to be filled. Fills
       *  orders and any order completely filled 
       *  is moved from pending to applied.
       */
      //void submit_order( const market_order::ptr& order );
      void submit_order( dbo::ptr<market_order> order );
      void close_order( const market_order::ptr& order );
      void update_fill_trx( const market_order::ptr& order );

     private:
      dbo::Session& m_session;
  };

}

#endif
