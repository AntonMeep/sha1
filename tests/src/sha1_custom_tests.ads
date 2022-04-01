with AUnit.Test_Fixtures;
with AUnit.Test_Suites;

package SHA1_Custom_Tests is
   function Suite return AUnit.Test_Suites.Access_Test_Suite;
private
   type Fixture is new AUnit.Test_Fixtures.Test_Fixture with null record;

   procedure SHA1_Test (Object : in out Fixture);
   procedure SHA1_One_Million_Test (Object : in out Fixture);
   procedure SHA1_Extremely_Long_Test (Object : in out Fixture);
end SHA1_Custom_Tests;
