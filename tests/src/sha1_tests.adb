with AUnit.Reporter.Text;
with AUnit.Run;
with AUnit.Test_Suites;

with SHA1_Streams_Tests;
with SHA1_Custom_Tests;

procedure SHA1_Tests is
   function Suite return AUnit.Test_Suites.Access_Test_Suite;

   procedure Runner is new AUnit.Run.Test_Runner (Suite);

   Reporter : AUnit.Reporter.Text.Text_Reporter;

   Test_Suite : aliased AUnit.Test_Suites.Test_Suite;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
   begin
      Test_Suite.Add_Test (SHA1_Streams_Tests.Suite);
      Test_Suite.Add_Test (SHA1_Custom_Tests.Suite);

      return Test_Suite'Unchecked_Access;
   end Suite;
begin
   Reporter.Set_Use_ANSI_Colors (True);
   Runner (Reporter);
end SHA1_Tests;
