#include "server.hpp"
#include <Wt/WServer>
#include <boost/exception/diagnostic_information.hpp>
#include <ltl/identity.hpp>
#include <ltl/asset.hpp>
#include <ltl/account.hpp>
#include <ltl/transaction.hpp>

#include <log/log.hpp>

int main( int argc, char** argv ) {
  try {
  Wt::WServer server("ltl::server");
  server.setServerConfiguration( argc, argv, WTHTTP_CONFIGURATION );

  boost::filesystem::create_directories("db");
  ltl::server::ptr ms( new ltl::server( "db") );
  ltl::dbo::ptr<ltl::identity>   dan                 = ms->create_identity( "dan", "danprops" );
  ltl::dbo::ptr<ltl::identity>   scott               = ms->create_identity( "scott", "scottprops" );
  ltl::dbo::ptr<ltl::asset>      corn                = ms->create_asset( "corn", "gmo" );
  ltl::dbo::ptr<ltl::asset_note> dans_corn           = ms->create_asset_note(dan, corn, "dans corn", "cool" ); 

  ltl::dbo::ptr<ltl::account> dans_dans_corn_acnt    = ms->create_account( dan, dans_corn );
  ltl::dbo::ptr<ltl::account> scotts_dans_corn_acnt  = ms->create_account( scott, dans_corn );

  try {
  // this should throw because scott has a 0 balance and cannot issue because he is not signer on note
  ltl::dbo::ptr<ltl::transaction> trx  = ms->transfer( "Sell corn", 10, scotts_dans_corn_acnt, dans_dans_corn_acnt );
  } catch ( const boost::exception& e ) {
    wlog("Expected Exception: %1%",boost::diagnostic_information(e));
  }

  slog( "creating first transaction" );
  // transfer 10 corn from dan_dans_corn to scotts_dans_corn
  ltl::dbo::ptr<ltl::transaction> trx  = ms->transfer( "Issue corn",10, dans_dans_corn_acnt, scotts_dans_corn_acnt );

  std::vector<ltl::sha1> req = trx->get_required_signatures();
  for( uint32_t i = 0; i < req.size(); ++i ) {
    slog( "required signature %1%", std::string(req[i]) );
  }

  slog( "Dan's Corn:\n%1%", dans_dans_corn_acnt->to_string() );
  slog( "Scott's Corn:\n%1%", scotts_dans_corn_acnt->to_string() );

  wlog( "Allocating Signature Numbers" );
  ms->allocate_signature_numbers( dans_dans_corn_acnt, 10 );
  ms->allocate_signature_numbers( scotts_dans_corn_acnt, 5 );
  slog( "Dan's Corn:\n%1%", dans_dans_corn_acnt->to_string() );

  wlog( "Accepting Balance" );
  ms->accept_applied_transactions( dans_dans_corn_acnt );
  ms->accept_applied_transactions( scotts_dans_corn_acnt );
  slog( "Dan's Corn:\n%1%", dans_dans_corn_acnt->to_string() );

  wlog( "Signing tranaction" );
  ms->sign_transaction( trx, dans_dans_corn_acnt );
  slog( "Dan's Corn:\n%1%", dans_dans_corn_acnt->to_string() );
  ms->sign_transaction( trx, scotts_dans_corn_acnt );
  slog( "Scott's Corn:\n%1%", scotts_dans_corn_acnt->to_string() );
  slog( "Dan's Corn:\n%1%", dans_dans_corn_acnt->to_string() );

  wlog( "Accepting Dan's Balance" );
  ms->accept_applied_transactions( dans_dans_corn_acnt );
  slog( "Dan's Corn:\n%1%", dans_dans_corn_acnt->to_string() );

  wlog( "Accepting Scott's Balance" );
  ms->accept_applied_transactions( scotts_dans_corn_acnt );
  slog( "Scott's Corn:\n%1%", scotts_dans_corn_acnt->to_string() );
 // trx->sign( dans_dans_corn_acnt );
  

  // at this point both dan & scott should have a pending, unsigned transaction in their inbox

  if( server.start() ) {
    int sig = Wt::WServer::waitForShutdown();
    std::cerr << "Shutting down (signal = " << sig <<")\n";
    server.stop();
  }

  } catch ( const boost::exception& e ) {
    std::cerr<<boost::diagnostic_information(e);
  } catch ( const std::exception& e ) {
    std::cerr<<boost::diagnostic_information(e);
  } catch ( ... ) {
    std::cerr<<"Unhandled exception\n";
  }
}
