#include <ltl/market.hpp>
#include <ltl/persist.hpp>
#include <ltl/error.hpp>

namespace ltl {

market_order::market_order( const dbo::ptr<transaction>& _otrx ) {
  order_trx = _otrx;
  
  const std::vector<action::ptr>& acts = order_trx->get_actions();
  if( acts.size() == 0 ) {
    LTL_THROW( "Invalid transaction for market order" );
  }

  boost::shared_ptr<offer> off = boost::dynamic_pointer_cast<offer>(acts[0]);
  if( !off ) {
    LTL_THROW( "First action is not a market offer" );
  }
  
  end_date   = to_milliseconds(off->end); 
  start_date = to_milliseconds(off->start); 
  price      = off->offer_price;
  num        = off->amount;
  min_unit   = off->min_amount;


  dbo::ptr<account> sacnt = order_trx->session()->load<account>(std::string(off->asset_account));
  dbo::ptr<account> cacnt = order_trx->session()->load<account>(std::string(off->currency_account));

  stock_note = std::string(sacnt->type()->get_id());
  cur_note   = std::string(cacnt->type()->get_id());
}

market::market( dbo::Session& s )
:m_session(s) {
}

market::~market() {
}

typedef dbo::collection<market_order::ptr> market_orders;
void market::submit_order(  dbo::ptr<market_order> order ) {
  dbo::Transaction dbtrx(m_session);
  if( !order->order_trx ) {
    LTL_THROW( "No order transaction specified." );
  }
  /// TODO: Verify that order_trx is valid and signed by host.
  /// TODO: Verify that sufficient funds exist in payment account

  dbo::ptr<market_order> o = m_session.add(order);

  market_order::order_type counter_type = o->type == market_order::buy ? market_order::sell : market_order::buy;

  // select all sell orders where price <= o->price
  if( o->type == market_order::buy ) {  
      long long now = to_milliseconds( to_ptime( system_clock::now() ) );
      if( now < o->start_date || now > o->end_date ) {
         // Not time to process this trx yet
      } else {
         market_orders mos = m_session.find<market_order>()
                             .where( "type = ? AND price <= ? AND num_unfilled >= ? AND start_date < ? AND end_date < ? " )
                             .orderBy( "price ASC" )
                             .bind( market_order::sell )
                             .bind( o->price )
                             .bind( o->min_unit )
                             .bind( now )
                             .bind( now );
         
         // keep the results around..
         std::vector<market_order::ptr> sell_orders;
         market_orders::iterator itr = mos.begin();
         while( itr != mos.end() ) {
           sell_orders.push_back(*itr);
         }
         
         for( uint32_t i = 0; i < sell_orders.size(); ++i ) {
           // we can fill part of our order...
           market_trade::ptr mt( new market_trade( o, sell_orders[i] ) );
           mt.modify()->num       = (std::min)(o->num_unfilled, sell_orders[i]->num_unfilled );
           mt.modify()->price     = sell_orders[i]->price;
           mt.modify()->timestamp = now;

           o.modify()->num_unfilled              -= mt->num;
           sell_orders[i].modify()->num_unfilled -= mt->num;

           m_session.add(mt);

           update_fill_trx(sell_orders[i]);

           if( o->num_unfilled == 0 ) {
              update_fill_trx(o);
              close_order( o );
              i = sell_orders.size(); // we are done
           }
           if( sell_orders[i]->num_unfilled == 0 ) {
              close_order( sell_orders[i] );
           }
         }
         update_fill_trx(o);
      }
  } else if ( o->type == market_order::sell ) {


  }

  dbtrx.commit();
}

void market::update_fill_trx( const market_order::ptr& mo ) {
  
}

void market::close_order( const market_order::ptr& mo ) {
  

}

market_trade::market_trade( const market_order::ptr& b, const market_order::ptr& s )
:buy_order(b), sell_order(s) {

}

} // namespace ltl
