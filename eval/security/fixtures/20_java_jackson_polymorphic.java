// Fixture 20: deserialize(). Reviewer should flag CWE-502.
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;

public class PayloadLoader {

    private final ObjectMapper mapper;

    public PayloadLoader() {
        this.mapper = new ObjectMapper();
        this.mapper.activateDefaultTyping(
            LaissezFaireSubTypeValidator.instance,
            ObjectMapper.DefaultTyping.NON_FINAL
        );
    }

    public Object deserialize(String json) throws Exception {
        return mapper.readValue(json, Object.class);
    }
}
